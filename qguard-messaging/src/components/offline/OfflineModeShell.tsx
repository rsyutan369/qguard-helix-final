import { useEffect, useState, type ReactNode } from "react";
import { ArrowLeftRight, History, LogOut, Moon, Network, RefreshCw, ShieldCheck, SlidersHorizontal, Sun, WifiOff } from "lucide-react";
import type { OfflineSessionInfo } from "@/lib/auth-context";
import type { OfflinePageId } from "@/lib/offline";
import type { Page } from "@/lib/types";
import type { ThemeMode } from "@/lib/use-theme";

export type OfflineRoute = OfflinePageId;

const OFFLINE_ROUTES: readonly OfflineRoute[] = ["mesh", "xfer", "transfer-history", "offline-settings"];

export function isOfflineRoute(page: Page): page is OfflineRoute {
  return (OFFLINE_ROUTES as readonly Page[]).includes(page);
}

const TABS: { route: OfflineRoute; label: string; icon: typeof Network }[] = [
  { route: "mesh", label: "Mesh", icon: Network },
  { route: "xfer", label: "XFER", icon: ArrowLeftRight },
  { route: "transfer-history", label: "History", icon: History },
  { route: "offline-settings", label: "Settings", icon: SlidersHorizontal },
];

/** Offline notices, placed where the online notification stack sits. */
export function OfflineNoticeStack({ children }: { children: ReactNode }) {
  if (!children) return null;
  return (
    <div className="fixed inset-x-3 top-[calc(env(safe-area-inset-top,0px)+150px)] z-[60] flex flex-col gap-2 sm:inset-x-auto sm:right-5 sm:top-[132px] sm:w-[390px]">
      {children}
    </div>
  );
}

function formatUntil(seconds: number): string {
  return new Date(seconds * 1000).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

function useBrowserOnline(): boolean {
  const [online, setOnline] = useState(() => typeof navigator === "undefined" || navigator.onLine !== false);
  useEffect(() => {
    const update = () => setOnline(navigator.onLine !== false);
    window.addEventListener("online", update);
    window.addEventListener("offline", update);
    return () => {
      window.removeEventListener("online", update);
      window.removeEventListener("offline", update);
    };
  }, []);
  return online;
}

/**
 * The app while signed in WITHOUT internet. Mesh and XFER run exactly as they
 * do online (device-to-device, hybrid post-quantum encrypted); the online
 * services are not mounted at all, so neither mode can disturb the other.
 */
export function OfflineModeShell({
  session,
  android,
  entitled,
  page,
  title,
  theme,
  onToggleTheme,
  onNavigate,
  onReconnect,
  onSignInOnline,
  onSignOut,
  overlays,
  children,
}: {
  session: OfflineSessionInfo;
  android: boolean;
  /** The plan this device last confirmed online still grants access. */
  entitled: boolean;
  page: OfflineRoute;
  title: string;
  theme: ThemeMode;
  onToggleTheme: () => void;
  onNavigate: (page: Page) => void;
  /** Android: try the stored session now. */
  onReconnect: () => Promise<boolean>;
  /** Desktop: leave offline mode for the online sign-in screen. */
  onSignInOnline: () => Promise<void>;
  onSignOut: () => Promise<void>;
  overlays?: ReactNode;
  children: ReactNode;
}) {
  const online = useBrowserOnline();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [confirmSignOut, setConfirmSignOut] = useState(false);

  const reconnect = async () => {
    setBusy(true);
    setMessage(null);
    try {
      if (android) {
        const restored = await onReconnect();
        if (!restored) setMessage("Still offline. Qguard keeps trying every 30 seconds.");
      } else {
        await onSignInOnline();
      }
    } finally {
      setBusy(false);
    }
  };

  const action = android ? "Reconnect now" : "Sign in online";

  return (
    <div className="qg-stage flex h-[100dvh] w-screen flex-col overflow-hidden bg-canvas">
      {overlays}
      <header className="mobile-safe-top z-30 shrink-0 border-b border-line bg-white">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-3 px-4 pb-3 pt-3 sm:px-5">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-violet-700 text-white" aria-hidden>
            <WifiOff size={19} />
          </span>
          <div className="min-w-0 flex-1">
            <h1 className="truncate text-base font-bold text-ink-950">{title}</h1>
            <p className="truncate text-xs text-ink-600">
              Offline mode{session.email ? ` · ${session.email}` : ""}
            </p>
          </div>
          {/* Beside the title on wide screens; a full-width row on a phone. */}
          <button type="button" onClick={() => void reconnect()} disabled={busy}
            className="order-last flex min-h-11 w-full items-center justify-center gap-2 rounded-xl bg-violet-700 px-4 text-xs font-bold text-white hover:bg-violet-800 disabled:opacity-60 focus-visible:outline focus-visible:outline-2 focus-visible:outline-violet-500 sm:order-none sm:w-auto">
            <RefreshCw size={15} aria-hidden className={busy ? "animate-spin" : undefined} /> {action}
          </button>
          <button type="button" onClick={onToggleTheme} aria-label={theme === "dark" ? "Use light theme" : "Use dark theme"}
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-line text-ink-700 hover:bg-canvas focus-visible:outline focus-visible:outline-2 focus-visible:outline-violet-500">
            {theme === "dark" ? <Sun size={17} aria-hidden /> : <Moon size={17} aria-hidden />}
          </button>
          <button type="button" onClick={() => setConfirmSignOut(true)} aria-label="Sign out" aria-expanded={confirmSignOut}
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-line text-ink-700 hover:bg-canvas focus-visible:outline focus-visible:outline-2 focus-visible:outline-violet-500">
            <LogOut size={17} aria-hidden />
          </button>
        </div>
        {confirmSignOut && (
          <div role="group" aria-label="Confirm sign out" className="mx-auto flex max-w-7xl flex-wrap items-center gap-2 px-4 pb-3 sm:px-5">
            <p className="min-w-0 flex-1 text-xs text-ink-700">
              {android
                ? "Signing out removes this device's stored session: you'll need internet to sign in again."
                : "You'll need internet, or this device's offline sign-in, to get back in."}
            </p>
            <button type="button" onClick={() => void onSignOut()}
              className="min-h-11 rounded-xl border border-rose-200 bg-rose-50 px-3 text-xs font-bold text-rose-700 hover:bg-rose-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-rose-500">
              Sign out of this device
            </button>
            <button type="button" onClick={() => setConfirmSignOut(false)}
              className="min-h-11 rounded-xl border border-line px-3 text-xs font-bold text-ink-700 hover:bg-canvas">
              Cancel
            </button>
          </div>
        )}
        <div className="mx-auto max-w-7xl px-4 pb-3 sm:px-5">
          <div role="status" className="flex items-start gap-2 rounded-xl border border-line bg-canvas px-3 py-2 text-xs text-ink-700">
            <ShieldCheck size={16} aria-hidden className="mt-0.5 shrink-0 text-emerald-700" />
            <p className="min-w-0">
              <span className="font-bold text-ink-950">No internet needed for Mesh and XFER.</span>{" "}
              Messages and files go device-to-device, encrypted with ML-KEM-768 + X25519, signed with ML-DSA-65 + Ed25519,
              sealed with AES-256-GCM and checked with SHA3-256. Secure Chat, Calls and Quantum Vault come back when you're online.
              {" "}Offline access on this device lasts until {formatUntil(session.offlineUntil)}.
              {android ? " You'll return online by yourself when the connection is back." : online ? " A connection looks available: sign in online to use everything." : ""}
            </p>
          </div>
          {message && <p role="status" className="mt-2 text-xs font-semibold text-ink-700">{message}</p>}
        </div>
        <nav aria-label="Offline workspaces" className="mx-auto grid max-w-7xl grid-cols-[repeat(4,minmax(0,1fr))] gap-2 px-4 pb-3 sm:flex sm:px-5">
          {TABS.map((tab) => {
            const active = tab.route === page;
            return (
              <button key={tab.route} type="button" aria-current={active ? "page" : undefined} onClick={() => onNavigate(tab.route)}
                className={`flex min-h-12 min-w-0 flex-col items-center justify-center gap-1 rounded-xl px-2 text-[11px] font-bold focus-visible:outline focus-visible:outline-2 focus-visible:outline-violet-500 sm:min-h-11 sm:flex-row sm:gap-2 sm:px-4 sm:text-xs ${active ? "bg-violet-700 text-white" : "border border-line text-ink-700 hover:bg-canvas"}`}>
                <tab.icon size={16} aria-hidden /> {tab.label}
              </button>
            );
          })}
        </nav>
      </header>
      <main className="min-h-0 flex-1 overflow-y-auto p-4 sm:p-5">
        {entitled ? children : (
          <div className="shell-card mx-auto max-w-xl p-6">
            <h2 className="text-base font-bold text-ink-950">Your plan couldn't be confirmed offline</h2>
            <p className="mt-2 text-sm text-ink-700">
              Mesh and XFER use the plan this device last confirmed online, and none is active. Connect to the internet
              and sign in once to confirm your plan; offline use then works again without a connection.
            </p>
            <button type="button" onClick={() => void reconnect()} disabled={busy}
              className="mt-4 min-h-11 rounded-xl bg-violet-700 px-4 text-xs font-bold text-white hover:bg-violet-800 disabled:opacity-60">
              {action}
            </button>
          </div>
        )}
      </main>
    </div>
  );
}
