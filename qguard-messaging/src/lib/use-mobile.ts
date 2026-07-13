import { useEffect, useState } from "react";

/**
 * Phone-layout breakpoint. Matches the Android build and any narrow desktop
 * window, so the mobile shell is testable on desktop by resizing.
 */
export const MOBILE_BREAKPOINT_PX = 860;

const QUERY = `(max-width: ${MOBILE_BREAKPOINT_PX}px)`;

/** True when the viewport is phone-sized; live-updates on rotation/resize. */
export function useIsMobile(): boolean {
  const [isMobile, setIsMobile] = useState(() =>
    typeof window !== "undefined" ? window.matchMedia(QUERY).matches : false,
  );

  useEffect(() => {
    const media = window.matchMedia(QUERY);
    const onChange = (event: MediaQueryListEvent) => setIsMobile(event.matches);
    media.addEventListener("change", onChange);
    setIsMobile(media.matches);
    return () => media.removeEventListener("change", onChange);
  }, []);

  return isMobile;
}
