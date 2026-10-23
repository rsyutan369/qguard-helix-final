import { useEffect, useRef, useState, type RefObject } from "react";
import jsQR from "jsqr";

/**
 * Camera QR scanning that works in every runtime this app ships in.
 *
 * The Shape Detection API (`BarcodeDetector`) is used when the WebView has it,
 * but neither Android System WebView nor Windows WebView2 exposes it, so the
 * fallback decodes video frames with jsQR on a canvas. Frames are sampled a few
 * times a second, not every animation frame — decoding is CPU work and a phone
 * holding a camera open is already warm.
 */

type BarcodeDetectorLike = new (options?: { formats?: string[] }) => {
  detect(source: HTMLVideoElement): Promise<Array<{ rawValue?: string }>>;
};

const SAMPLE_INTERVAL_MS = 160;
/** Downscale big camera frames before decoding; QR finder patterns survive this easily. */
const MAX_DECODE_EDGE = 720;

export interface QrScannerState {
  videoRef: RefObject<HTMLVideoElement | null>;
  error: string | null;
  starting: boolean;
}

function describeCameraError(error: unknown): string {
  const name = error instanceof DOMException ? error.name : "";
  if (name === "NotAllowedError" || name === "SecurityError") {
    return "Camera access was denied. Allow camera access for QGuard Helix in your device settings, or type the code instead.";
  }
  if (name === "NotFoundError" || name === "OverconstrainedError") return "No camera was found on this device. Type the code shown under the QR instead.";
  if (name === "NotReadableError") return "The camera is in use by another app. Close it and try again.";
  return "The camera couldn't be started. Type the code shown under the QR instead.";
}

export function useQrScanner(active: boolean, onResult: (value: string) => void): QrScannerState {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const resultRef = useRef(onResult);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  resultRef.current = onResult;

  useEffect(() => {
    if (!active) return undefined;
    let cancelled = false;
    let stream: MediaStream | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const canvas = document.createElement("canvas");
    const context = canvas.getContext("2d", { willReadFrequently: true });

    const Detector = (window as unknown as { BarcodeDetector?: BarcodeDetectorLike }).BarcodeDetector;
    let detector: InstanceType<BarcodeDetectorLike> | null = null;
    try {
      detector = Detector ? new Detector({ formats: ["qr_code"] }) : null;
    } catch {
      detector = null;
    }

    async function decode(video: HTMLVideoElement): Promise<string | null> {
      if (detector) {
        try {
          const codes = await detector.detect(video);
          return codes.find((code) => code.rawValue)?.rawValue ?? null;
        } catch {
          detector = null; // fall through to jsQR for the rest of this session
        }
      }
      if (!context || !video.videoWidth || !video.videoHeight) return null;
      const scale = Math.min(1, MAX_DECODE_EDGE / Math.max(video.videoWidth, video.videoHeight));
      canvas.width = Math.round(video.videoWidth * scale);
      canvas.height = Math.round(video.videoHeight * scale);
      context.drawImage(video, 0, 0, canvas.width, canvas.height);
      const frame = context.getImageData(0, 0, canvas.width, canvas.height);
      return jsQR(frame.data, frame.width, frame.height, { inversionAttempts: "attemptBoth" })?.data ?? null;
    }

    async function tick() {
      const video = videoRef.current;
      if (cancelled || !video) return;
      const value = video.readyState >= 2 ? await decode(video) : null;
      if (cancelled) return;
      if (value) {
        resultRef.current(value);
        return;
      }
      timer = setTimeout(() => void tick(), SAMPLE_INTERVAL_MS);
    }

    async function startCamera() {
      setError(null);
      if (!navigator.mediaDevices?.getUserMedia) {
        setError("This device can't open a camera here. Type the code shown under the QR instead.");
        return;
      }
      setStarting(true);
      try {
        stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: { ideal: "environment" }, width: { ideal: 1280 }, height: { ideal: 720 } },
          audio: false,
        });
        if (cancelled || !videoRef.current) return;
        videoRef.current.srcObject = stream;
        videoRef.current.setAttribute("playsinline", "true");
        await videoRef.current.play();
        void tick();
      } catch (cause) {
        if (!cancelled) setError(describeCameraError(cause));
      } finally {
        if (!cancelled) setStarting(false);
      }
    }

    void startCamera();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
      stream?.getTracks().forEach((track) => track.stop());
      if (videoRef.current) videoRef.current.srcObject = null;
    };
  }, [active]);

  return { videoRef, error, starting };
}
