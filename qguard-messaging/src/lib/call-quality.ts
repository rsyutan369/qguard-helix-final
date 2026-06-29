// Adaptive call media quality. Capping capture resolution/framerate and the
// encoder bitrate is what keeps WebRTC from saturating WebView2's (often
// software) encoder and freezing the app/device. Defaults to "auto" (~360p);
// users on strong machines can opt into "hd".

export type CallQuality = "low" | "auto" | "hd";

export const DEFAULT_CALL_QUALITY: CallQuality = "auto";

interface QualityTier {
  width: number;
  height: number;
  frameRate: number;
  /** Target video encoder ceiling, bits per second. */
  maxBitrate: number;
}

const TIERS: Record<CallQuality, QualityTier> = {
  low: { width: 320, height: 180, frameRate: 15, maxBitrate: 150_000 },
  auto: { width: 640, height: 360, frameRate: 24, maxBitrate: 500_000 },
  hd: { width: 1280, height: 720, frameRate: 30, maxBitrate: 1_500_000 },
};

export function qualityLabel(quality: CallQuality): string {
  if (quality === "low") return "Low";
  if (quality === "hd") return "HD";
  return "Auto";
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
 * Cap each video sender's encoder so it scales resolution DOWN under CPU/network
 * pressure instead of stalling (the core freeze fix). Best-effort: unsupported
 * `setParameters` fields are ignored by the browser.
 */
export async function applySenderParams(pc: RTCPeerConnection, quality: CallQuality): Promise<void> {
  const tier = TIERS[quality];
  await Promise.all(
    pc.getSenders().map(async (sender) => {
      if (sender.track?.kind !== "video") return;
      try {
        const params = sender.getParameters();
        // Prefer dropping resolution to keep the call smooth under load.
        (params as RTCRtpSendParameters & { degradationPreference?: RTCDegradationPreference }).degradationPreference =
          "maintain-framerate";
        if (!params.encodings || params.encodings.length === 0) {
          params.encodings = [{}];
        }
        params.encodings.forEach((encoding) => {
          encoding.maxBitrate = tier.maxBitrate;
          encoding.maxFramerate = tier.frameRate;
          encoding.scaleResolutionDownBy = 1;
        });
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
