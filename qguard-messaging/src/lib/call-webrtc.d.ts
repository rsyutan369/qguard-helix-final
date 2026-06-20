export {};
declare global {
  interface RTCEncodedVideoFrame { readonly type: "key" | "delta"; data: ArrayBuffer; }
  interface RTCEncodedAudioFrame { data: ArrayBuffer; }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const RTCRtpScriptTransform: { new (worker: Worker, options?: any, transfer?: any[]): any };
  interface RTCRtpSender { transform?: unknown; }
  interface RTCRtpReceiver { transform?: unknown; }
}