import { useCallback, useEffect, useRef, useState } from "react";
import { CloudOff, Loader2, RefreshCcw, ServerCrash, WifiOff } from "lucide-react";
import { checkForAppUpdate } from "@/lib/app-update";
import {
  RELAY_TROUBLE_EVENT,
  classifyRelayHealth,
  nextRecheckMs,
  probeRelay,
  type ControlProbe,
  type RelayHealth,
} from "@/lib/relay-health";
import { supabaseAnonKey, supabaseUrl } from "@/lib/supabase";
import { isAndroidRuntime, isTauriRuntime } from "@/lib/tauri";

async function probeControl(): Promise<ControlProbe> {
  // The signed-update check is the only other host this app talks to, and it
  // exists only in the desktop app.
  if (!isTauriRuntime() || isAndroidRuntime()) return "unavailable";
  try {
    await checkForAppUpdate();
    return "reachable";
  } catch {
    return "unreachable";
  }
}

/**
 * Relay outage / block banner (roadmap 9.2). Silent while the relay answers.
 * Checks on launch, when the OS reports a network change, when the app comes
 * back to the foreground, and when realtime reports trouble; while unhealthy
 * it rechecks with backoff and disappears on its own once the relay answers.
 */
export function RelayHealthBanner() {
  const [health, setHealth] = useState<RelayHealth | null>(null);
  const [checking, setChecking] = useState(false);
  const failuresRef = useRef(0);
  const timerRef = useRef<number | null>(null);
  const inFlightRef = useRef(false);
  const lastOkAtRef = useRef(0);

  // `force` = a real signal (network change, realtime trouble, a tap); a plain
  // return to the foreground re-asks at most every 30 s while things are fine.
  const check = useCallback(async (force = true) => {
    if (inFlightRef.current) return;
    if (!force && Date.now() - lastOkAtRef.current < 30_000) return;
    inFlightRef.current = true;
    setChecking(true);
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    try {
      const relay = await probeRelay(supabaseUrl, supabaseAnonKey);
      const healthy = relay.kind === "ok" || (relay.kind === "http_error" && relay.status < 500);
      // Only spend a control probe when the relay itself failed.
      const control = healthy || relay.kind === "not_configured" ? "unavailable" : await probeControl();
      const next = classifyRelayHealth({ online: navigator.onLine, relay, control });
      setHealth(next);
      if (next.state === "ok") {
        failuresRef.current = 0;
        lastOkAtRef.current = Date.now();
      } else if (next.state !== "not_configured") {
        failuresRef.current += 1;
        timerRef.current = window.setTimeout(() => { void check(); }, nextRecheckMs(failuresRef.current));
      }
    } finally {
      inFlightRef.current = false;
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    void check();
    const onChange = () => { void check(); };
    const onVisible = () => { if (document.visibilityState === "visible") void check(false); };
    window.addEventListener("online", onChange);
    window.addEventListener("offline", onChange);
    window.addEventListener(RELAY_TROUBLE_EVENT, onChange);
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.removeEventListener("online", onChange);
      window.removeEventListener("offline", onChange);
      window.removeEventListener(RELAY_TROUBLE_EVENT, onChange);
      document.removeEventListener("visibilitychange", onVisible);
      if (timerRef.current !== null) window.clearTimeout(timerRef.current);
    };
  }, [check]);

  if (!health || health.state === "ok" || health.state === "not_configured") return null;
  const Icon = health.state === "offline" || health.state === "relay_unreachable_no_internet"
    ? WifiOff
    : health.state === "relay_failing" ? ServerCrash : CloudOff;

  return (
    <div role="status" className="fixed bottom-[calc(env(safe-area-inset-bottom)+5.5rem)] left-1/2 z-[60] flex w-[min(94vw,620px)] -translate-x-1/2 items-start gap-3 rounded-xl border border-amber-300 bg-amber-50 px-4 py-2.5 text-sm text-amber-950 shadow-soft md:bottom-4">
      <Icon size={18} className="mt-0.5 shrink-0 text-amber-700" />
      <div className="min-w-0 flex-1">
        <div className="font-bold">{health.title}</div>
        <div className="text-xs leading-relaxed">{health.detail}</div>
      </div>
      <button
        type="button"
        onClick={() => { failuresRef.current = 0; void check(); }}
        disabled={checking}
        className="flex shrink-0 items-center gap-1.5 rounded-md border border-amber-300 bg-white px-2.5 py-1 text-xs font-bold text-amber-900 hover:bg-amber-100 disabled:opacity-60"
      >
        {checking ? <Loader2 size={13} className="animate-spin" /> : <RefreshCcw size={13} />} Check again
      </button>
    </div>
  );
}
