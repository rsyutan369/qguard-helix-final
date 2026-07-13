/// <reference lib="webworker" />
import { makeFrameTransform, type FrameCryptoOptions } from "@/lib/call-media-transform";

// Standard RTCRtpScriptTransform worker entrypoint (Chromium >= 115). The same
// per-frame AES-256-GCM transform runs on the main thread via createEncodedStreams
// on older WebView2 builds — see makeFrameTransform / use-secure-call.ts.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function run(transformer: any, opts: FrameCryptoOptions) {
  const transform = await makeFrameTransform(opts);
  transformer.readable.pipeThrough(transform).pipeTo(transformer.writable);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(self as unknown as { onrtctransform: (e: any) => void }).onrtctransform = (event: any) => {
  void run(event.transformer, event.transformer.options as FrameCryptoOptions);
};
