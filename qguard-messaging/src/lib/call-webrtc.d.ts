export {};
declare global {
  interface RTCEncodedVideoFrame { readonly type: "key" | "delta"; data: ArrayBuffer; }
  interface RTCEncodedAudioFrame { data: ArrayBuffer; }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const RTCRtpScriptTransform: { new (worker: Worker, options?: any, transfer?: any[]): any };
  interface RTCInsertableStreams { readable: ReadableStream; writable: WritableStream; }
  // `transform` (Chromium >= 115) and `createEncodedStreams` (Chromium 86-114)
  // are the two encoded-transform plumbings; one or the other is present.
  interface RTCRtpSender { transform?: unknown; createEncodedStreams?: () => RTCInsertableStreams; }
  interface RTCRtpReceiver { transform?: unknown; createEncodedStreams?: () => RTCInsertableStreams; }
  // Chromium flag that must be set at RTCPeerConnection construction to enable
  // the legacy createEncodedStreams() API.
  interface RTCConfiguration { encodedInsertableStreams?: boolean; }
}