/**
 * Screen share (roadmap 7.3).
 *
 * The captured screen track replaces the camera track on the call's existing
 * video sender (use-secure-call.ts), so it goes through the same per-frame
 * AES-256-GCM transform and the same pinned VP8 codec as the camera; the
 * frame-crypto header offsets in call-frame-crypto.ts are VP8's and stay valid.
 */

/**
 * Whether this WebView can capture a screen. Desktop WebViews (WebView2,
 * WebKitGTK, WKWebView) implement getDisplayMedia; Android's WebView does not.
 */
export function screenShareSupported(nav: Navigator | undefined = typeof navigator === "undefined" ? undefined : navigator): boolean {
  return typeof nav?.mediaDevices?.getDisplayMedia === "function";
}

/** Text and UI over motion: 15 fps is plenty, and the encoder keeps resolution. */
export const SCREEN_SHARE_CONSTRAINTS: DisplayMediaStreamOptions = {
  video: { frameRate: { ideal: 15, max: 30 } },
  audio: false,
};
