/// <reference lib="webworker" />
import { importAesGcmKey, sealFrame, openFrame } from "@/lib/call-frame-crypto";

// Unencrypted header bytes the RTP packetizer needs (Chrome insertable-streams convention).
function headerLength(kind: "audio" | "video", frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame): number {
  if (kind === "audio") return 1;
  return (frame as RTCEncodedVideoFrame).type === "key" ? 10 : 3;
}

interface XfOptions { operation: "encrypt" | "decrypt"; keyB64: string; contextTag: number[]; kind: "audio" | "video"; }

async function run(transformer: any, opts: XfOptions) {
  const raw = Uint8Array.from(atob(opts.keyB64), (c) => c.charCodeAt(0));
  const key = await importAesGcmKey(raw);
  const ctx = new Uint8Array(opts.contextTag);
  let counter = 0n;
  const transform = new TransformStream({
    async transform(frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame, controller) {
      const data = new Uint8Array(frame.data);
      const hl = headerLength(opts.kind, frame);
      try {
        frame.data = opts.operation === "encrypt"
          ? await sealFrame(key, ctx, counter++, hl, data)
          : await openFrame(key, ctx, hl, data);
        controller.enqueue(frame);
      } catch {
        // Drop frames that fail auth (do not forward plaintext or corrupt media).
      }
    },
  });
  transformer.readable.pipeThrough(transform).pipeTo(transformer.writable);
}

// Standard RTCRtpScriptTransform entrypoint.
(self as unknown as { onrtctransform: (e: any) => void }).onrtctransform = (event: any) => {
  void run(event.transformer, event.transformer.options as XfOptions);
};