import { useEffect, useRef, useState } from "react";
import { DownloadCloud, RefreshCcw, X } from "lucide-react";
import { isTauriRuntime } from "@/lib/tauri";

type UpdatePhase =
  | { kind: "hidden" }
  | { kind: "available"; version: string }
  | { kind: "downloading"; version: string; percent: number | null }
  | { kind: "ready"; version: string }
  | { kind: "error"; message: string };

// One silent check per app launch; module flag survives remounts.
let checkedThisSession = false;

/**
 * Signed auto-update flow (Tauri updater plugin). Checks once at startup;
 * when a newer signed release is published (public/downloads/latest.json on
 * the platform), shows a compact banner: download happens in-app, then one
 * click relaunches into the new version. All failures are silent — an offline
 * user or an unreachable endpoint must never see an error for a background
 * check they didn't ask for.
 */
export function UpdateBanner() {
  const [phase, setPhase] = useState<UpdatePhase>({ kind: "hidden" });
  const updateRef = useRef<import("@tauri-apps/plugin-updater").Update | null>(null);

  useEffect(() => {
    if (!isTauriRuntime() || checkedThisSession) return;
    checkedThisSession = true;
    let cancelled = false;
    (async () => {
      try {
        const { check } = await import("@tauri-apps/plugin-updater");
        const update = await check();
        if (cancelled || !update) return;
        updateRef.current = update;
        setPhase({ kind: "available", version: update.version });
      } catch {
        // Silent: offline, endpoint not deployed yet, or signature mismatch.
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const install = async () => {
    const update = updateRef.current;
    if (!update) return;
    setPhase({ kind: "downloading", version: update.version, percent: null });
    try {
      let total = 0;
      let received = 0;
      await update.downloadAndInstall((event) => {
        if (event.event === "Started") total = event.data.contentLength ?? 0;
        if (event.event === "Progress") {
          received += event.data.chunkLength;
          setPhase({
            kind: "downloading",
            version: update.version,
            percent: total > 0 ? Math.min(100, Math.round((received / total) * 100)) : null,
          });
        }
      });
      setPhase({ kind: "ready", version: update.version });
    } catch (error) {
      setPhase({ kind: "error", message: error instanceof Error ? error.message : "Update failed — try again later." });
    }
  };

  const relaunchNow = async () => {
    try {
      const { relaunch } = await import("@tauri-apps/plugin-process");
      await relaunch();
    } catch {
      setPhase({ kind: "error", message: "Installed — restart QGuard Messaging to finish the update." });
    }
  };

  if (phase.kind === "hidden") return null;

  return (
    <div className="fixed left-1/2 top-3 z-[60] w-[min(94vw,560px)] -translate-x-1/2 rounded-xl border border-cyan-200 bg-white p-3 shadow-soft">
      <div className="flex items-center gap-3">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-cyan-50 text-cyan-600">
          <DownloadCloud size={18} />
        </span>
        <div className="min-w-0 flex-1 text-sm">
          {phase.kind === "available" && (
            <>
              <div className="font-bold text-ink-950">Update available — QGuard Messaging v{phase.version}</div>
              <div className="text-xs text-ink-600">Security and reliability improvements. Installs in the background.</div>
            </>
          )}
          {phase.kind === "downloading" && (
            <div className="font-semibold text-ink-950">
              Downloading v{phase.version}{phase.percent !== null ? ` — ${phase.percent}%` : "..."}
            </div>
          )}
          {phase.kind === "ready" && (
            <div className="font-bold text-ink-950">v{phase.version} installed — restart to finish</div>
          )}
          {phase.kind === "error" && <div className="font-semibold text-rose-600">{phase.message}</div>}
        </div>
        {phase.kind === "available" && (
          <button type="button" onClick={() => void install()} className="rounded-lg bg-cyan-600 px-4 py-2 text-xs font-bold text-white hover:bg-cyan-700">
            Update now
          </button>
        )}
        {phase.kind === "ready" && (
          <button type="button" onClick={() => void relaunchNow()} className="flex items-center gap-1.5 rounded-lg bg-emerald-600 px-4 py-2 text-xs font-bold text-white hover:bg-emerald-700">
            <RefreshCcw size={14} /> Restart now
          </button>
        )}
        {(phase.kind === "available" || phase.kind === "error") && (
          <button type="button" aria-label="Dismiss" onClick={() => setPhase({ kind: "hidden" })} className="rounded-lg p-1.5 text-ink-400 hover:bg-canvas hover:text-ink-700">
            <X size={16} />
          </button>
        )}
      </div>
    </div>
  );
}
