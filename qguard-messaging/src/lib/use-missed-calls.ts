// The number of missed calls not yet looked at, for badges. Read from the
// core (readable while Secure Chat is locked, like the unread count) and
// refreshed whenever the history changes or the app comes back to the front.

import { useEffect, useState } from "react";
import { CALL_LOG_CHANGED, callHistory } from "@/lib/call-history";

export function useMissedCallCount(): number {
  const [count, setCount] = useState(0);
  useEffect(() => {
    let cancelled = false;
    const refresh = () => {
      callHistory.missedCount().then(
        (value) => { if (!cancelled) setCount(Math.max(0, Number(value) || 0)); },
        () => undefined,
      );
    };
    const onVisible = () => { if (document.visibilityState === "visible") refresh(); };
    refresh();
    window.addEventListener(CALL_LOG_CHANGED, refresh);
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      cancelled = true;
      window.removeEventListener(CALL_LOG_CHANGED, refresh);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, []);
  return count;
}
