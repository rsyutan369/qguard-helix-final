import { Bell, CircleHelp, LogOut, Moon, Search, Sparkles, Sun } from "lucide-react";
import type { User } from "@supabase/supabase-js";
import { useEffect, useMemo, useRef, useState } from "react";
import { describeLiveEvent, liveStatusLabel } from "@/lib/live-sse";
import type { QGuardLiveEvent, QGuardLiveStatus } from "@/lib/live-sse";
import type { ThemeMode } from "@/lib/use-theme";

interface TopBarProps {
  title: string;
  subtitle: string;
  user: User;
  theme: ThemeMode;
  activePage: string;
  liveStatus: QGuardLiveStatus;
  lastLiveEvent: QGuardLiveEvent | null;
  unreadMessages?: number;
  onOpenChat?: () => void;
  onToggleTheme: () => void;
  onSignOut: () => void;
  onStartTour: () => void;
}

function initials(user: User): string {
  const name = String(user.user_metadata?.full_name ?? user.email ?? "User");
  return name
    .split(/[\s@.]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("") || "U";
}

export default function TopBar({ title, subtitle, user, theme, activePage, liveStatus, lastLiveEvent, unreadMessages = 0, onOpenChat, onToggleTheme, onSignOut, onStartTour }: TopBarProps) {
  const [panel, setPanel] = useState<"search" | "notifications" | "help" | null>(null);
  const [search, setSearch] = useState("");
  const headerRef = useRef<HTMLElement>(null);

  // Close any open panel when navigating to another page.
  useEffect(() => { setPanel(null); }, [activePage]);

  // Close on outside click (incl. sidebar navigation) and on Escape, so a panel
  // never lingers over other pages.
  useEffect(() => {
    if (!panel) return undefined;
    const onPointerDown = (event: MouseEvent) => {
      if (headerRef.current && !headerRef.current.contains(event.target as Node)) setPanel(null);
    };
    const onKeyDown = (event: KeyboardEvent) => { if (event.key === "Escape") setPanel(null); };
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [panel]);
  const liveTone = liveStatus.state === "live"
    ? "bg-emerald-50 text-emerald-600"
    : liveStatus.state === "connecting"
      ? "bg-cyan-50 text-cyan-700"
      : liveStatus.state === "fallback"
        ? "bg-amber-50 text-amber-700"
        : "bg-rose-50 text-rose-600";
  const searchSummary = useMemo(() => {
    const clean = search.trim().toLowerCase();
    if (!clean) return "Type to filter the current secure workspace context.";
    return `Search queued for "${clean}". Workspace-wide encrypted content remains client-local.`;
  }, [search]);

  return (
    <header ref={headerRef} className="relative z-40 flex h-[76px] items-center justify-between border-b border-line bg-white/75 px-7 backdrop-blur-xl">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-ink-950">{title}</h1>
        <p className="mt-1 text-sm text-ink-600">{subtitle}</p>
      </div>
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => setPanel(panel === "search" ? null : "search")}
          className="flex h-10 w-[260px] items-center gap-2 rounded-lg border border-line bg-canvas px-3 text-left text-sm text-ink-400 transition hover:border-cyan-200 hover:bg-white"
        >
          <Search size={17} />
          <span>Search secure workspace</span>
        </button>
        <span className={`status-pill ${liveTone}`} title={liveStatusLabel(liveStatus.state)}>
          {liveStatus.state}
        </span>
        <button className="icon-button relative" title="Notifications" onClick={() => setPanel(panel === "notifications" ? null : "notifications")}>
          <Bell size={18} />
          {unreadMessages > 0 && (
            <span className="absolute -right-1 -top-1 flex h-[18px] min-w-[18px] items-center justify-center rounded-full bg-rose-500 px-1 text-[10px] font-bold leading-none text-white shadow-tight">
              {unreadMessages > 99 ? "99+" : unreadMessages}
            </span>
          )}
        </button>
        <button data-tour="help" className="icon-button" title="Security help" onClick={() => setPanel(panel === "help" ? null : "help")}>
          <CircleHelp size={18} />
        </button>
        <button className="icon-button" title="Toggle theme" onClick={onToggleTheme}>
          {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
        </button>
        <button className="icon-button" title="Sign out" onClick={onSignOut}>
          <LogOut size={18} />
        </button>
        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-violet-600 text-sm font-bold text-white">
          {initials(user)}
        </div>
      </div>
      {panel && (
        <div className="absolute right-7 top-[66px] z-50 w-[360px] rounded-lg border border-line bg-white/95 p-4 shadow-soft backdrop-blur-xl">
          {panel === "search" && (
            <div>
              <div className="text-sm font-bold text-ink-950">Workspace Search</div>
              <input
                value={search}
                onChange={(event) => setSearch(event.currentTarget.value)}
                className="mt-3 w-full rounded-lg border border-line bg-canvas px-3 py-2 text-sm outline-none focus:border-cyan-300"
                autoFocus
              />
              <div className="mt-3 text-xs leading-5 text-ink-600">{searchSummary}</div>
            </div>
          )}
          {panel === "notifications" && (
            <div>
              <div className="text-sm font-bold text-ink-950">Live Activity</div>
              {unreadMessages > 0 && (
                <button
                  type="button"
                  onClick={() => {
                    setPanel(null);
                    onOpenChat?.();
                  }}
                  className="focus-ring mt-3 flex w-full items-center gap-3 rounded-lg border border-violet-100 bg-violet-50 p-3 text-left transition hover:bg-violet-100"
                >
                  <span className="flex h-6 min-w-[24px] items-center justify-center rounded-full bg-violet-600 px-1.5 text-[11px] font-bold text-white">
                    {unreadMessages > 99 ? "99+" : unreadMessages}
                  </span>
                  <span>
                    <span className="block text-sm font-semibold text-ink-900">
                      Unread encrypted message{unreadMessages === 1 ? "" : "s"}
                    </span>
                    <span className="mt-0.5 block text-xs text-ink-500">Open Secure Chat to read and mark as read.</span>
                  </span>
                </button>
              )}
              {lastLiveEvent ? (
                <div className="mt-3 rounded-lg border border-line bg-canvas p-3">
                  <div className="text-sm font-semibold text-ink-900">{describeLiveEvent(lastLiveEvent).title}</div>
                  <div className="mt-1 text-xs text-ink-400">{describeLiveEvent(lastLiveEvent).meta}</div>
                </div>
              ) : (
                <div className="mt-3 rounded-lg border border-line bg-canvas p-3 text-xs text-ink-500">
                  You&apos;re all caught up. New workspace activity will appear here.
                </div>
              )}
              <div className="mt-2 text-[11px] text-ink-400">{liveStatusLabel(liveStatus.state)}</div>
            </div>
          )}
          {panel === "help" && (
            <div>
              <div className="text-sm font-bold text-ink-950">Security Help</div>
              <div className="mt-3 grid gap-2 text-xs leading-5 text-ink-600">
                <div>Your messages and private keys are encrypted on this device and never leave it in readable form.</div>
                <div>Every conversation is protected with end-to-end, quantum-safe encryption.</div>
                <div>The live indicator shows when your workspace is receiving real-time updates.</div>
              </div>
              <button
                type="button"
                onClick={() => {
                  setPanel(null);
                  onStartTour();
                }}
                className="focus-ring mt-4 flex w-full items-center justify-center gap-2 rounded-lg border border-violet-100 bg-violet-50 px-3 py-2 text-xs font-bold text-violet-600 transition hover:bg-violet-100"
              >
                <Sparkles size={14} />
                Replay product tour
              </button>
            </div>
          )}
        </div>
      )}
    </header>
  );
}
