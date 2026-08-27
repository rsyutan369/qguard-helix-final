import { isAndroidRuntime } from "@/lib/tauri";

/**
 * Root attribute that scopes the Modernist skin.
 *
 * Every rule in styles/android-modernist.css hangs off
 * `html[data-qg-skin="modernist"]`, so the sheet is inert until this attribute
 * is set. That is the whole Android-only boundary: desktop builds — and a
 * narrow desktop window that trips the <=860px mobile shell — never set it and
 * therefore keep the Cold Fusion look untouched.
 */
export const SKIN_ATTR = "data-qg-skin";
export const MODERNIST = "modernist";

/**
 * True when the Modernist skin is active. Components use this only to add the
 * extra STRUCTURE the design calls for (the ink masthead, the edge-to-edge tab
 * rail); everything that is purely visual is handled by the stylesheet, so no
 * component needs a second render path.
 */
export function isModernistSkin(): boolean {
  return typeof document !== "undefined"
    && document.documentElement.getAttribute(SKIN_ATTR) === MODERNIST;
}

/**
 * Applies the skin on the Android build. Called once from main.tsx BEFORE the
 * first React render so the very first paint is already Modernist — setting it
 * from an effect would flash the Cold Fusion palette on cold start.
 */
export function applyAndroidSkin(): void {
  if (typeof document === "undefined") return;
  if (!isAndroidRuntime()) return;
  document.documentElement.setAttribute(SKIN_ATTR, MODERNIST);
}
