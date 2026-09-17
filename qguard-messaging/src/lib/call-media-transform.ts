import { importAesGcmKey, sealFrame, openFrame, headerLength, frameCounter, FrameReplayWindow } from "@/lib/call-frame-crypto";

export interface FrameCryptoOptions {
  operation: "encrypt" | "decrypt";
  keyB64: string;
  kind: "audio" | "video";
  contextTag: number[];
}

/**
 * Build the AES-256-GCM per-frame TransformStream used by BOTH encoded-transform
 * plumbings:
 *   - the worker `RTCRtpScriptTransform` path (call-crypto-worker.ts), used when
 *     the runtime is Chromium >= 115; and
 *   - the main-thread `createEncodedStreams` fallback (see use-secure-call.ts),
 *     used on older WebView2 builds (Chromium 86-114) that lack
 *     RTCRtpScriptTransform.
 *
 * The wire format is identical either way, so a peer running one plumbing
 * interoperates cleanly with a peer running the other (host <-> VM).
 */
export async function makeFrameTransform(opts: FrameCryptoOptions): Promise<TransformStream> {
  const raw = Uint8Array.from(atob(opts.keyB64), (c) => c.charCodeAt(0));
  const key = await importAesGcmKey(raw);
  const ctx = new Uint8Array(opts.contextTag);
  let counter = 0n;
  // Receive side only: one window per (direction, media kind), which is exactly
  // the scope of one key + contextTag pair, so audio and video never share it.
  const replay = opts.operation === "decrypt" ? new FrameReplayWindow() : null;
  return new TransformStream({
    async transform(frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame, controller) {
      const data = new Uint8Array(frame.data);
      const hl = headerLength(opts.kind, frame as { type?: "key" | "delta" });
      try {
        if (replay) {
          // Check before opening, commit after: a forged counter must not be
          // able to consume a window slot or push the high-water mark forward.
          const seq = frameCounter(data);
          if (!replay.check(seq)) return;
          frame.data = await openFrame(key, ctx, hl, data);
          replay.commit(seq);
        } else {
          frame.data = await sealFrame(key, ctx, counter++, hl, data);
        }
        controller.enqueue(frame);
      } catch {
        // Drop frames that fail AES-GCM auth — never forward plaintext or
        // corrupt media. GCM gives per-frame integrity/authenticity only.
      }
    },
  });
}
